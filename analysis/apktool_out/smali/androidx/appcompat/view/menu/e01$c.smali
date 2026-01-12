.class public final Landroidx/appcompat/view/menu/e01$c;
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
.field public static final n:Landroidx/appcompat/view/menu/e01$c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/e01$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e01$c;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/e01$c;->n:Landroidx/appcompat/view/menu/e01$c;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x2

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/k01;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/k01;
    .locals 1

    instance-of v0, p2, Landroidx/appcompat/view/menu/d01;

    if-eqz v0, :cond_0

    check-cast p2, Landroidx/appcompat/view/menu/d01;

    iget-object v0, p1, Landroidx/appcompat/view/menu/k01;->a:Landroidx/appcompat/view/menu/jh;

    invoke-interface {p2, v0}, Landroidx/appcompat/view/menu/d01;->C(Landroidx/appcompat/view/menu/jh;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Landroidx/appcompat/view/menu/k01;->a(Landroidx/appcompat/view/menu/d01;Ljava/lang/Object;)V

    :cond_0
    return-object p1
.end method

.method public bridge synthetic h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/k01;

    check-cast p2, Landroidx/appcompat/view/menu/jh$b;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/e01$c;->a(Landroidx/appcompat/view/menu/k01;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/k01;

    move-result-object p1

    return-object p1
.end method
