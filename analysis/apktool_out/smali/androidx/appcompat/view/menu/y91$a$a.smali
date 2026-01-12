.class public final Landroidx/appcompat/view/menu/y91$a$a;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/jw;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/y91$a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# static fields
.field public static final n:Landroidx/appcompat/view/menu/y91$a$a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/y91$a$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/y91$a$a;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/y91$a$a;->n:Landroidx/appcompat/view/menu/y91$a$a;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/y91;)Landroidx/appcompat/view/menu/y91;
    .locals 1

    const-string v0, "it"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method

.method public bridge synthetic i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/y91;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/y91$a$a;->a(Landroidx/appcompat/view/menu/y91;)Landroidx/appcompat/view/menu/y91;

    move-result-object p1

    return-object p1
.end method
