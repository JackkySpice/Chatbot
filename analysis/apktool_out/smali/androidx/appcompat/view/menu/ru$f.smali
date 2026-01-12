.class public final enum Landroidx/appcompat/view/menu/ru$f;
.super Ljava/lang/Enum;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ru;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "f"
.end annotation


# static fields
.field public static final enum m:Landroidx/appcompat/view/menu/ru$f;

.field public static final enum n:Landroidx/appcompat/view/menu/ru$f;

.field public static final enum o:Landroidx/appcompat/view/menu/ru$f;

.field public static final enum p:Landroidx/appcompat/view/menu/ru$f;

.field public static final synthetic q:[Landroidx/appcompat/view/menu/ru$f;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Landroidx/appcompat/view/menu/ru$f;

    const-string v1, "NONE"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/ru$f;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroidx/appcompat/view/menu/ru$f;->m:Landroidx/appcompat/view/menu/ru$f;

    new-instance v0, Landroidx/appcompat/view/menu/ru$f;

    const-string v1, "LEFT"

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/ru$f;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroidx/appcompat/view/menu/ru$f;->n:Landroidx/appcompat/view/menu/ru$f;

    new-instance v0, Landroidx/appcompat/view/menu/ru$f;

    const-string v1, "RIGHT"

    const/4 v2, 0x2

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/ru$f;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroidx/appcompat/view/menu/ru$f;->o:Landroidx/appcompat/view/menu/ru$f;

    new-instance v0, Landroidx/appcompat/view/menu/ru$f;

    const-string v1, "BOTH"

    const/4 v2, 0x3

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/ru$f;-><init>(Ljava/lang/String;I)V

    sput-object v0, Landroidx/appcompat/view/menu/ru$f;->p:Landroidx/appcompat/view/menu/ru$f;

    invoke-static {}, Landroidx/appcompat/view/menu/ru$f;->c()[Landroidx/appcompat/view/menu/ru$f;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/ru$f;->q:[Landroidx/appcompat/view/menu/ru$f;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method

.method public static synthetic c()[Landroidx/appcompat/view/menu/ru$f;
    .locals 4

    sget-object v0, Landroidx/appcompat/view/menu/ru$f;->m:Landroidx/appcompat/view/menu/ru$f;

    sget-object v1, Landroidx/appcompat/view/menu/ru$f;->n:Landroidx/appcompat/view/menu/ru$f;

    sget-object v2, Landroidx/appcompat/view/menu/ru$f;->o:Landroidx/appcompat/view/menu/ru$f;

    sget-object v3, Landroidx/appcompat/view/menu/ru$f;->p:Landroidx/appcompat/view/menu/ru$f;

    filled-new-array {v0, v1, v2, v3}, [Landroidx/appcompat/view/menu/ru$f;

    move-result-object v0

    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Landroidx/appcompat/view/menu/ru$f;
    .locals 1

    const-class v0, Landroidx/appcompat/view/menu/ru$f;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Landroidx/appcompat/view/menu/ru$f;

    return-object p0
.end method

.method public static values()[Landroidx/appcompat/view/menu/ru$f;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/ru$f;->q:[Landroidx/appcompat/view/menu/ru$f;

    invoke-virtual {v0}, [Landroidx/appcompat/view/menu/ru$f;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Landroidx/appcompat/view/menu/ru$f;

    return-object v0
.end method
