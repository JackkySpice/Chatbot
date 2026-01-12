.class public abstract Landroidx/appcompat/view/menu/y90$a;
.super Landroidx/appcompat/view/menu/d5;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/y90;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "a"
.end annotation


# instance fields
.field public final b:Landroidx/appcompat/view/menu/y90;

.field public c:Landroidx/appcompat/view/menu/y90;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/y90;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/d5;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/y90$a;->b:Landroidx/appcompat/view/menu/y90;

    return-void
.end method


# virtual methods
.method public bridge synthetic b(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/y90;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/y90$a;->e(Landroidx/appcompat/view/menu/y90;Ljava/lang/Object;)V

    return-void
.end method

.method public e(Landroidx/appcompat/view/menu/y90;Ljava/lang/Object;)V
    .locals 2

    if-nez p2, :cond_0

    const/4 p2, 0x1

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-eqz p2, :cond_1

    iget-object v0, p0, Landroidx/appcompat/view/menu/y90$a;->b:Landroidx/appcompat/view/menu/y90;

    goto :goto_1

    :cond_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/y90$a;->c:Landroidx/appcompat/view/menu/y90;

    :goto_1
    if-eqz v0, :cond_2

    invoke-static {}, Landroidx/appcompat/view/menu/y90;->j()Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v1

    invoke-static {v1, p1, p0, v0}, Landroidx/appcompat/view/menu/q;->a(Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    if-eqz p2, :cond_2

    iget-object p1, p0, Landroidx/appcompat/view/menu/y90$a;->b:Landroidx/appcompat/view/menu/y90;

    iget-object p2, p0, Landroidx/appcompat/view/menu/y90$a;->c:Landroidx/appcompat/view/menu/y90;

    invoke-static {p2}, Landroidx/appcompat/view/menu/x50;->b(Ljava/lang/Object;)V

    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/y90;->g(Landroidx/appcompat/view/menu/y90;Landroidx/appcompat/view/menu/y90;)V

    :cond_2
    return-void
.end method
