.class public Landroidx/appcompat/view/menu/qv$b;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/sc0;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/qv;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/qv;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/qv;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/qv$b;->a:Landroidx/appcompat/view/menu/qv;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroid/view/MenuItem;)Z
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/qv$b;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/qv;->C(Landroid/view/MenuItem;)Z

    move-result p1

    return p1
.end method

.method public b(Landroid/view/Menu;Landroid/view/MenuInflater;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/qv$b;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/qv;->x(Landroid/view/Menu;Landroid/view/MenuInflater;)Z

    return-void
.end method

.method public c(Landroid/view/Menu;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/qv$b;->a:Landroidx/appcompat/view/menu/qv;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/qv;->F(Landroid/view/Menu;)Z

    return-void
.end method
