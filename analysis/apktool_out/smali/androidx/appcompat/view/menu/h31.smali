.class public final Landroidx/appcompat/view/menu/h31;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/xs;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/jh;

.field public final b:Ljava/lang/Object;

.field public final c:Landroidx/appcompat/view/menu/xw;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/jh;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Landroidx/appcompat/view/menu/h31;->a:Landroidx/appcompat/view/menu/jh;

    invoke-static {p2}, Landroidx/appcompat/view/menu/e01;->b(Landroidx/appcompat/view/menu/jh;)Ljava/lang/Object;

    move-result-object p2

    iput-object p2, p0, Landroidx/appcompat/view/menu/h31;->b:Ljava/lang/Object;

    new-instance p2, Landroidx/appcompat/view/menu/h31$a;

    const/4 v0, 0x0

    invoke-direct {p2, p1, v0}, Landroidx/appcompat/view/menu/h31$a;-><init>(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)V

    iput-object p2, p0, Landroidx/appcompat/view/menu/h31;->c:Landroidx/appcompat/view/menu/xw;

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/h31;->a:Landroidx/appcompat/view/menu/jh;

    iget-object v1, p0, Landroidx/appcompat/view/menu/h31;->b:Ljava/lang/Object;

    iget-object v2, p0, Landroidx/appcompat/view/menu/h31;->c:Landroidx/appcompat/view/menu/xw;

    invoke-static {v0, p1, v1, v2, p2}, Landroidx/appcompat/view/menu/va;->b(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p2

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method
