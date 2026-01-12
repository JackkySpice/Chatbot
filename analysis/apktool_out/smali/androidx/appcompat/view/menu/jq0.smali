.class public final synthetic Landroidx/appcompat/view/menu/jq0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ar0$b;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ar0;

.field public final synthetic b:Ljava/util/List;

.field public final synthetic c:Landroidx/appcompat/view/menu/z11;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ar0;Ljava/util/List;Landroidx/appcompat/view/menu/z11;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/jq0;->a:Landroidx/appcompat/view/menu/ar0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/jq0;->b:Ljava/util/List;

    iput-object p3, p0, Landroidx/appcompat/view/menu/jq0;->c:Landroidx/appcompat/view/menu/z11;

    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/jq0;->a:Landroidx/appcompat/view/menu/ar0;

    iget-object v1, p0, Landroidx/appcompat/view/menu/jq0;->b:Ljava/util/List;

    iget-object v2, p0, Landroidx/appcompat/view/menu/jq0;->c:Landroidx/appcompat/view/menu/z11;

    check-cast p1, Landroid/database/Cursor;

    invoke-static {v0, v1, v2, p1}, Landroidx/appcompat/view/menu/ar0;->B(Landroidx/appcompat/view/menu/ar0;Ljava/util/List;Landroidx/appcompat/view/menu/z11;Landroid/database/Cursor;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
