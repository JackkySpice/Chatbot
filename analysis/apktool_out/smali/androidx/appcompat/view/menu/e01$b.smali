.class public final Landroidx/appcompat/view/menu/e01$b;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/xw;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/e01;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# static fields
.field public static final n:Landroidx/appcompat/view/menu/e01$b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/e01$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e01$b;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/e01$b;->n:Landroidx/appcompat/view/menu/e01$b;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x2

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/d01;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/d01;
    .locals 0

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    instance-of p1, p2, Landroidx/appcompat/view/menu/d01;

    if-eqz p1, :cond_1

    check-cast p2, Landroidx/appcompat/view/menu/d01;

    goto :goto_0

    :cond_1
    const/4 p2, 0x0

    :goto_0
    return-object p2
.end method

.method public bridge synthetic h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/d01;

    check-cast p2, Landroidx/appcompat/view/menu/jh$b;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/e01$b;->a(Landroidx/appcompat/view/menu/d01;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/d01;

    move-result-object p1

    return-object p1
.end method
